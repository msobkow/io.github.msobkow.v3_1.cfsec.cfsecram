
// Description: Java 25 in-memory RAM DbIO implementation for SecUser.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecUserTable in-memory RAM DbIO implementation
 *	for SecUser.
 */
public class CFSecRamSecUserTable
	implements ICFSecSecUserTable
{
	private ICFSecSchema schema;
	private Map< ICFLibKeyHash256,
				CFSecBuffSecUser > dictByPKey
		= new HashMap< ICFLibKeyHash256,
				CFSecBuffSecUser >();
	private Map< CFSecBuffSecUserByULoginIdxKey,
			CFSecBuffSecUser > dictByULoginIdx
		= new HashMap< CFSecBuffSecUserByULoginIdxKey,
			CFSecBuffSecUser >();
	private Map< CFSecBuffSecUserByEMAddrIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUser >> dictByEMAddrIdx
		= new HashMap< CFSecBuffSecUserByEMAddrIdxKey,
				Map< ICFLibKeyHash256,
					CFSecBuffSecUser >>();

	public CFSecRamSecUserTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecUser ensureRec(ICFSecSecUser rec) {
		return (((CFSecBuffSecUserFactoryService)(schema.getCFSecBuffFactory().getFactorySecUser())).ensureRec(rec));
	}

	@Override
	public ICFSecSecUser createSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser iBuff )
	{
		final String S_ProcName = "createSecUser";
		
		CFSecBuffSecUser Buff = (CFSecBuffSecUser)ensureRec(iBuff);
		ICFLibKeyHash256 pkey;
		pkey = schema.nextSecUserIdGen();
		Buff.setRequiredSecUserId( pkey );
		CFSecBuffSecUserByULoginIdxKey keyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecBuffSecUserByEMAddrIdxKey keyEMAddrIdx = (CFSecBuffSecUserByEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByEMAddrIdxKey();
		keyEMAddrIdx.setRequiredEMailAddress( Buff.getRequiredEMailAddress() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByULoginIdx.containsKey( keyULoginIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserLoginIdx",
				"SecUserLoginIdx",
				keyULoginIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.put( keyULoginIdx, Buff );

		Map< ICFLibKeyHash256, CFSecBuffSecUser > subdictEMAddrIdx;
		if( dictByEMAddrIdx.containsKey( keyEMAddrIdx ) ) {
			subdictEMAddrIdx = dictByEMAddrIdx.get( keyEMAddrIdx );
		}
		else {
			subdictEMAddrIdx = new HashMap< ICFLibKeyHash256, CFSecBuffSecUser >();
			dictByEMAddrIdx.put( keyEMAddrIdx, subdictEMAddrIdx );
		}
		subdictEMAddrIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecUser.CLASS_CODE) {
				CFSecBuffSecUser retbuff = ((CFSecBuffSecUser)(schema.getCFSecBuffFactory().getFactorySecUser().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecUser readDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerived";
		ICFSecSecUser buff;
		if( PKey == null ) {
			return( null );
		}
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser lockDerived( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.lockDerived";
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUser.readAllDerived";
		ICFSecSecUser[] retList = new ICFSecSecUser[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecUser > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecUser readDerivedByULoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByULoginIdx";
		CFSecBuffSecUserByULoginIdxKey key = (CFSecBuffSecUserByULoginIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByULoginIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecUser buff;
		if( dictByULoginIdx.containsKey( key ) ) {
			buff = dictByULoginIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser[] readDerivedByEMAddrIdx( ICFSecAuthorization Authorization,
		String EMailAddress )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByEMAddrIdx";
		CFSecBuffSecUserByEMAddrIdxKey key = (CFSecBuffSecUserByEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByEMAddrIdxKey();

		key.setRequiredEMailAddress( EMailAddress );
		ICFSecSecUser[] recArray;
		if( dictByEMAddrIdx.containsKey( key ) ) {
			Map< ICFLibKeyHash256, CFSecBuffSecUser > subdictEMAddrIdx
				= dictByEMAddrIdx.get( key );
			recArray = new ICFSecSecUser[ subdictEMAddrIdx.size() ];
			Iterator< CFSecBuffSecUser > iter = subdictEMAddrIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< ICFLibKeyHash256, CFSecBuffSecUser > subdictEMAddrIdx
				= new HashMap< ICFLibKeyHash256, CFSecBuffSecUser >();
			dictByEMAddrIdx.put( key, subdictEMAddrIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecUser readDerivedByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByIdIdx() ";
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( SecUserId ) ) {
			buff = dictByPKey.get( SecUserId );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser readRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readRec";
		ICFSecSecUser buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUser.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser lockRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecUser buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecUser.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecUser[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUser.readAllRec";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUser buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUser instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecUser[] pageAllRec( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecUser readRecByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByIdIdx() ";
		ICFSecSecUser buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
			return( (ICFSecSecUser)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUser readRecByULoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByULoginIdx() ";
		ICFSecSecUser buff = readDerivedByULoginIdx( Authorization,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
			return( (ICFSecSecUser)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecUser[] readRecByEMAddrIdx( ICFSecAuthorization Authorization,
		String EMailAddress )
	{
		final String S_ProcName = "CFSecRamSecUser.readRecByEMAddrIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByEMAddrIdx( Authorization,
			EMailAddress );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecUser.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key EMAddrIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailAddress	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecUser[] pageRecByEMAddrIdx( ICFSecAuthorization Authorization,
		String EMailAddress,
		ICFLibKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageRecByEMAddrIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecUser updateSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser iBuff )
	{
		CFSecBuffSecUser Buff = (CFSecBuffSecUser)ensureRec(iBuff);
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)Buff.getPKey();
		CFSecBuffSecUser existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUser",
				"Existing record not found",
				"Existing record not found",
				"SecUser",
				"SecUser",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUser",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserByULoginIdxKey existingKeyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByULoginIdxKey();
		existingKeyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecUserByULoginIdxKey newKeyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByULoginIdxKey();
		newKeyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecBuffSecUserByEMAddrIdxKey existingKeyEMAddrIdx = (CFSecBuffSecUserByEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByEMAddrIdxKey();
		existingKeyEMAddrIdx.setRequiredEMailAddress( existing.getRequiredEMailAddress() );

		CFSecBuffSecUserByEMAddrIdxKey newKeyEMAddrIdx = (CFSecBuffSecUserByEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByEMAddrIdxKey();
		newKeyEMAddrIdx.setRequiredEMailAddress( Buff.getRequiredEMailAddress() );

		// Check unique indexes

		if( ! existingKeyULoginIdx.equals( newKeyULoginIdx ) ) {
			if( dictByULoginIdx.containsKey( newKeyULoginIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUser",
					"SecUserLoginIdx",
					"SecUserLoginIdx",
					newKeyULoginIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< ICFLibKeyHash256, CFSecBuffSecUser > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.remove( existingKeyULoginIdx );
		dictByULoginIdx.put( newKeyULoginIdx, Buff );

		subdict = dictByEMAddrIdx.get( existingKeyEMAddrIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByEMAddrIdx.containsKey( newKeyEMAddrIdx ) ) {
			subdict = dictByEMAddrIdx.get( newKeyEMAddrIdx );
		}
		else {
			subdict = new HashMap< ICFLibKeyHash256, CFSecBuffSecUser >();
			dictByEMAddrIdx.put( newKeyEMAddrIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser iBuff )
	{
		final String S_ProcName = "CFSecRamSecUserTable.deleteSecUser() ";
		CFSecBuffSecUser Buff = (CFSecBuffSecUser)ensureRec(iBuff);
		int classCode;
		ICFLibKeyHash256 pkey = (ICFLibKeyHash256)(Buff.getPKey());
		CFSecBuffSecUser existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUser",
				pkey );
		}
					schema.getTableSecUserPassword().deleteSecUserPasswordByIdIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSysGrpMemb().deleteSecSysGrpMembByLoginIdx( Authorization,
						existing.getRequiredLoginId() );
					schema.getTableSecClusGrpMemb().deleteSecClusGrpMembByLoginIdx( Authorization,
						existing.getRequiredLoginId() );
					schema.getTableSecTentGrpMemb().deleteSecTentGrpMembByUserIdx( Authorization,
						existing.getRequiredLoginId() );
					schema.getTableSecUserPassword().deleteSecUserPasswordByIdIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecUserPWReset().deleteSecUserPWResetByIdIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecUserEMConf().deleteSecUserEMConfByIdIdx( Authorization,
						existing.getRequiredSecUserId() );
		CFSecBuffSecUserByULoginIdxKey keyULoginIdx = (CFSecBuffSecUserByULoginIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecUserByEMAddrIdxKey keyEMAddrIdx = (CFSecBuffSecUserByEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByEMAddrIdxKey();
		keyEMAddrIdx.setRequiredEMailAddress( existing.getRequiredEMailAddress() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< ICFLibKeyHash256, CFSecBuffSecUser > subdict;

		dictByPKey.remove( pkey );

		dictByULoginIdx.remove( keyULoginIdx );

		subdict = dictByEMAddrIdx.get( keyEMAddrIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecUserByIdIdx( ICFSecAuthorization Authorization,
		ICFLibKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecUser cur;
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserByULoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecUserByULoginIdxKey key = (CFSecBuffSecUserByULoginIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByULoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecUserByULoginIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserByULoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByULoginIdxKey argKey )
	{
		CFSecBuffSecUser cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}

	@Override
	public void deleteSecUserByEMAddrIdx( ICFSecAuthorization Authorization,
		String argEMailAddress )
	{
		CFSecBuffSecUserByEMAddrIdxKey key = (CFSecBuffSecUserByEMAddrIdxKey)schema.getCFSecBuffFactory().getFactorySecUser().newByEMAddrIdxKey();
		key.setRequiredEMailAddress( argEMailAddress );
		deleteSecUserByEMAddrIdx( Authorization, key );
	}

	@Override
	public void deleteSecUserByEMAddrIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByEMAddrIdxKey argKey )
	{
		CFSecBuffSecUser cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecUser> matchSet = new LinkedList<CFSecBuffSecUser>();
		Iterator<CFSecBuffSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecUser)(schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() ));
			deleteSecUser( Authorization, cur );
		}
	}
}
