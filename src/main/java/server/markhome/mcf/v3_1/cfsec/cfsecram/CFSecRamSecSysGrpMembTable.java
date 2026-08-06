
// Description: Java 25 in-memory RAM DbIO implementation for SecSysGrpMemb.

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

import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.buff.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecSysGrpMembTable in-memory RAM DbIO implementation
 *	for SecSysGrpMemb.
 */
public class CFSecRamSecSysGrpMembTable
	implements ICFSecSecSysGrpMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecSysGrpMembPKey,
				CFSecBuffSecSysGrpMemb > dictByPKey
		= new HashMap< ICFSecSecSysGrpMembPKey,
				CFSecBuffSecSysGrpMemb >();
	private Map< CFSecBuffSecSysGrpMembBySysGrpIdxKey,
				Map< CFSecBuffSecSysGrpMembPKey,
					CFSecBuffSecSysGrpMemb >> dictBySysGrpIdx
		= new HashMap< CFSecBuffSecSysGrpMembBySysGrpIdxKey,
				Map< CFSecBuffSecSysGrpMembPKey,
					CFSecBuffSecSysGrpMemb >>();
	private Map< CFSecBuffSecSysGrpMembByLoginIdxKey,
				Map< CFSecBuffSecSysGrpMembPKey,
					CFSecBuffSecSysGrpMemb >> dictByLoginIdx
		= new HashMap< CFSecBuffSecSysGrpMembByLoginIdxKey,
				Map< CFSecBuffSecSysGrpMembPKey,
					CFSecBuffSecSysGrpMemb >>();

	public CFSecRamSecSysGrpMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysGrpMemb ensureRec(ICFSecSecSysGrpMemb rec) {
		return (((CFSecBuffSecSysGrpMembFactoryService)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSysGrpMemb createSecSysGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMemb iBuff )
	{
		final String S_ProcName = "createSecSysGrpMemb";
		
		CFSecBuffSecSysGrpMemb Buff = (CFSecBuffSecSysGrpMemb)ensureRec(iBuff);
		CFSecBuffSecSysGrpMembPKey pkey = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		pkey.setRequiredSecSysGrpId(Buff.getRequiredSecSysGrpId());
		pkey.setRequiredLoginId(Buff.getRequiredLoginId());
		pkey.setRequiredSecSysGrpId( Buff.getRequiredSecSysGrpId() );
		pkey.setRequiredLoginId( Buff.getRequiredLoginId() );
		Buff.setRequiredContainerGroup( pkey.getRequiredSecSysGrpId() );
		Buff.setRequiredParentUser( pkey.getRequiredLoginId() );
		Buff.setRequiredSecSysGrpId( pkey.getRequiredSecSysGrpId() );
		Buff.setRequiredLoginId( pkey.getRequiredLoginId() );
		CFSecBuffSecSysGrpMembBySysGrpIdxKey keySysGrpIdx = (CFSecBuffSecSysGrpMembBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newBySysGrpIdxKey();
		keySysGrpIdx.setRequiredSecSysGrpId( Buff.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecSysGrpMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		// Validate foreign keys

		{
			boolean allNull = true;
			allNull = false;
			if( ! allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysGrpId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecSysGrpMembGroup",
						"SecSysGrpMembGroup",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdictSysGrpIdx;
		if( dictBySysGrpIdx.containsKey( keySysGrpIdx ) ) {
			subdictSysGrpIdx = dictBySysGrpIdx.get( keySysGrpIdx );
		}
		else {
			subdictSysGrpIdx = new HashMap< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb >();
			dictBySysGrpIdx.put( keySysGrpIdx, subdictSysGrpIdx );
		}
		subdictSysGrpIdx.put( pkey, Buff );

		Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdictLoginIdx;
		if( dictByLoginIdx.containsKey( keyLoginIdx ) ) {
			subdictLoginIdx = dictByLoginIdx.get( keyLoginIdx );
		}
		else {
			subdictLoginIdx = new HashMap< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb >();
			dictByLoginIdx.put( keyLoginIdx, subdictLoginIdx );
		}
		subdictLoginIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysGrpMemb.CLASS_CODE) {
				CFSecBuffSecSysGrpMemb retbuff = ((CFSecBuffSecSysGrpMemb)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysGrpMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId,
		String LoginId )
	{
		{	CFLibDbKeyHash256 testSecSysGrpId = SecSysGrpId;
			if (testSecSysGrpId == null) {
				return( null );
			}
		}
		{	String testLoginId = LoginId;
			if (testLoginId == null) {
				return( null );
			}
		}
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredLoginId( LoginId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecSysGrpMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readDerived";
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( PKey.getRequiredSecSysGrpId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecSysGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.lockDerived";
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( PKey.getRequiredSecSysGrpId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecSysGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readAllDerived";
		ICFSecSecSysGrpMemb[] retList = new ICFSecSecSysGrpMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysGrpMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysGrpMemb[] readDerivedBySysGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readDerivedBySysGrpIdx";
		CFSecBuffSecSysGrpMembBySysGrpIdxKey key = (CFSecBuffSecSysGrpMembBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newBySysGrpIdxKey();

		key.setRequiredSecSysGrpId( SecSysGrpId );
		ICFSecSecSysGrpMemb[] recArray;
		if( dictBySysGrpIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdictSysGrpIdx
				= dictBySysGrpIdx.get( key );
			recArray = new ICFSecSecSysGrpMemb[ subdictSysGrpIdx.size() ];
			Iterator< CFSecBuffSecSysGrpMemb > iter = subdictSysGrpIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdictSysGrpIdx
				= new HashMap< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb >();
			dictBySysGrpIdx.put( key, subdictSysGrpIdx );
			recArray = new ICFSecSecSysGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysGrpMemb[] readDerivedByLoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readDerivedByLoginIdx";
		CFSecBuffSecSysGrpMembByLoginIdxKey key = (CFSecBuffSecSysGrpMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newByLoginIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecSysGrpMemb[] recArray;
		if( dictByLoginIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdictLoginIdx
				= dictByLoginIdx.get( key );
			recArray = new ICFSecSecSysGrpMemb[ subdictLoginIdx.size() ];
			Iterator< CFSecBuffSecSysGrpMemb > iter = subdictLoginIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdictLoginIdx
				= new HashMap< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb >();
			dictByLoginIdx.put( key, subdictLoginIdx );
			recArray = new ICFSecSecSysGrpMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysGrpMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readDerivedByIdIdx() ";
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredLoginId( LoginId );
		ICFSecSecSysGrpMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpMemb readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId,
		String LoginId )
	{
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredLoginId( LoginId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecSysGrpMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readRec";
		ICFSecSecSysGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysGrpMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysGrpMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysGrpMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readAllRec";
		ICFSecSecSysGrpMemb buff;
		ArrayList<ICFSecSecSysGrpMemb> filteredList = new ArrayList<ICFSecSecSysGrpMemb>();
		ICFSecSecSysGrpMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrpMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecSysGrpMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysGrpMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysGrpMemb[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecSysGrpId,
		String priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysGrpMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readRecByIdIdx() ";
		ICFSecSecSysGrpMemb buff = readDerivedByIdIdx( Authorization,
			SecSysGrpId,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpMemb.CLASS_CODE ) ) {
			return( (ICFSecSecSysGrpMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysGrpMemb[] readRecBySysGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readRecBySysGrpIdx() ";
		ICFSecSecSysGrpMemb buff;
		ArrayList<ICFSecSecSysGrpMemb> filteredList = new ArrayList<ICFSecSecSysGrpMemb>();
		ICFSecSecSysGrpMemb[] buffList = readDerivedBySysGrpIdx( Authorization,
			SecSysGrpId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrpMemb[0] ) );
	}

	@Override
	public ICFSecSecSysGrpMemb[] readRecByLoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMemb.readRecByLoginIdx() ";
		ICFSecSecSysGrpMemb buff;
		ArrayList<ICFSecSecSysGrpMemb> filteredList = new ArrayList<ICFSecSecSysGrpMemb>();
		ICFSecSecSysGrpMemb[] buffList = readDerivedByLoginIdx( Authorization,
			LoginId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysGrpMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysGrpMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysGrpMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecSysGrpMemb buffer instances identified by the duplicate key SysGrpIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysGrpId	The SecSysGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpMemb[] pageRecBySysGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId,
		CFLibDbKeyHash256 priorSecSysGrpId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecBySysGrpIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSysGrpMemb buffer instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecSysGrpMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysGrpMemb[] pageRecByLoginIdx( ICFSecAuthorization Authorization,
		String LoginId,
		CFLibDbKeyHash256 priorSecSysGrpId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByLoginIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysGrpMemb updateSecSysGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMemb iBuff )
	{
		CFSecBuffSecSysGrpMemb Buff = (CFSecBuffSecSysGrpMemb)ensureRec(iBuff);
		CFSecBuffSecSysGrpMembPKey pkey = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		pkey = (CFSecBuffSecSysGrpMembPKey)Buff.getPKey();
		CFSecBuffSecSysGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysGrpMemb",
				"Existing record not found",
				"Existing record not found",
				"SecSysGrpMemb",
				"SecSysGrpMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysGrpMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysGrpMembBySysGrpIdxKey existingKeySysGrpIdx = (CFSecBuffSecSysGrpMembBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newBySysGrpIdxKey();
		existingKeySysGrpIdx.setRequiredSecSysGrpId( existing.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpMembBySysGrpIdxKey newKeySysGrpIdx = (CFSecBuffSecSysGrpMembBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newBySysGrpIdxKey();
		newKeySysGrpIdx.setRequiredSecSysGrpId( Buff.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpMembByLoginIdxKey existingKeyLoginIdx = (CFSecBuffSecSysGrpMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newByLoginIdxKey();
		existingKeyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecSysGrpMembByLoginIdxKey newKeyLoginIdx = (CFSecBuffSecSysGrpMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newByLoginIdxKey();
		newKeyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecSysGrp().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysGrpId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecSysGrpMemb",
						"Container",
						"Container",
						"SecSysGrpMembGroup",
						"SecSysGrpMembGroup",
						"SecSysGrp",
						"SecSysGrp",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictBySysGrpIdx.get( existingKeySysGrpIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySysGrpIdx.containsKey( newKeySysGrpIdx ) ) {
			subdict = dictBySysGrpIdx.get( newKeySysGrpIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb >();
			dictBySysGrpIdx.put( newKeySysGrpIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByLoginIdx.get( existingKeyLoginIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByLoginIdx.containsKey( newKeyLoginIdx ) ) {
			subdict = dictByLoginIdx.get( newKeyLoginIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb >();
			dictByLoginIdx.put( newKeyLoginIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysGrpMemb( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysGrpMembTable.deleteSecSysGrpMemb() ";
		CFSecBuffSecSysGrpMemb Buff = (CFSecBuffSecSysGrpMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecSysGrpMembPKey pkey = (CFSecBuffSecSysGrpMembPKey)(Buff.getPKey());
		CFSecBuffSecSysGrpMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysGrpMemb",
				pkey );
		}
		CFSecBuffSecSysGrpMembBySysGrpIdxKey keySysGrpIdx = (CFSecBuffSecSysGrpMembBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newBySysGrpIdxKey();
		keySysGrpIdx.setRequiredSecSysGrpId( existing.getRequiredSecSysGrpId() );

		CFSecBuffSecSysGrpMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecSysGrpMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecSysGrpMembPKey, CFSecBuffSecSysGrpMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySysGrpIdx.get( keySysGrpIdx );
		subdict.remove( pkey );

		subdict = dictByLoginIdx.get( keyLoginIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecSysGrpMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecSysGrpId,
		String LoginId )
	{
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( SecSysGrpId );
		key.setRequiredLoginId( LoginId );
		deleteSecSysGrpMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembPKey PKey )
	{
		CFSecBuffSecSysGrpMembPKey key = (CFSecBuffSecSysGrpMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newPKey());
		key.setRequiredSecSysGrpId( PKey.getRequiredSecSysGrpId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		CFSecBuffSecSysGrpMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysGrpMemb cur;
		LinkedList<CFSecBuffSecSysGrpMemb> matchSet = new LinkedList<CFSecBuffSecSysGrpMemb>();
		Iterator<CFSecBuffSecSysGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrpMemb)(schema.getTableSecSysGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId(),
				cur.getRequiredLoginId() ));
			deleteSecSysGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpMembBySysGrpIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecSysGrpId )
	{
		CFSecBuffSecSysGrpMembBySysGrpIdxKey key = (CFSecBuffSecSysGrpMembBySysGrpIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newBySysGrpIdxKey();
		key.setRequiredSecSysGrpId( argSecSysGrpId );
		deleteSecSysGrpMembBySysGrpIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpMembBySysGrpIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembBySysGrpIdxKey argKey )
	{
		CFSecBuffSecSysGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrpMemb> matchSet = new LinkedList<CFSecBuffSecSysGrpMemb>();
		Iterator<CFSecBuffSecSysGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrpMemb)(schema.getTableSecSysGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId(),
				cur.getRequiredLoginId() ));
			deleteSecSysGrpMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysGrpMembByLoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecSysGrpMembByLoginIdxKey key = (CFSecBuffSecSysGrpMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysGrpMemb().newByLoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecSysGrpMembByLoginIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysGrpMembByLoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysGrpMembByLoginIdxKey argKey )
	{
		CFSecBuffSecSysGrpMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysGrpMemb> matchSet = new LinkedList<CFSecBuffSecSysGrpMemb>();
		Iterator<CFSecBuffSecSysGrpMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysGrpMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysGrpMemb)(schema.getTableSecSysGrpMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysGrpId(),
				cur.getRequiredLoginId() ));
			deleteSecSysGrpMemb( Authorization, cur );
		}
	}
}
