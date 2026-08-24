
// Description: Java 25 in-memory RAM DbIO implementation for SecSysRoleMemb.

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
 *	CFSecRamSecSysRoleMembTable in-memory RAM DbIO implementation
 *	for SecSysRoleMemb.
 */
public class CFSecRamSecSysRoleMembTable
	implements ICFSecSecSysRoleMembTable
{
	private ICFSecSchema schema;
	private Map< ICFSecSecSysRoleMembPKey,
				CFSecBuffSecSysRoleMemb > dictByPKey
		= new HashMap< ICFSecSecSysRoleMembPKey,
				CFSecBuffSecSysRoleMemb >();
	private Map< CFSecBuffSecSysRoleMembBySysRoleIdxKey,
				Map< CFSecBuffSecSysRoleMembPKey,
					CFSecBuffSecSysRoleMemb >> dictBySysRoleIdx
		= new HashMap< CFSecBuffSecSysRoleMembBySysRoleIdxKey,
				Map< CFSecBuffSecSysRoleMembPKey,
					CFSecBuffSecSysRoleMemb >>();
	private Map< CFSecBuffSecSysRoleMembByLoginIdxKey,
				Map< CFSecBuffSecSysRoleMembPKey,
					CFSecBuffSecSysRoleMemb >> dictByLoginIdx
		= new HashMap< CFSecBuffSecSysRoleMembByLoginIdxKey,
				Map< CFSecBuffSecSysRoleMembPKey,
					CFSecBuffSecSysRoleMemb >>();

	public CFSecRamSecSysRoleMembTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public CFSecBuffSecSysRoleMemb ensureRec(ICFSecSecSysRoleMemb rec) {
		return (((CFSecBuffSecSysRoleMembFactoryService)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb())).ensureRec(rec));
	}

	@Override
	public ICFSecSecSysRoleMemb createSecSysRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMemb iBuff )
	{
		final String S_ProcName = "createSecSysRoleMemb";
		
		CFSecBuffSecSysRoleMemb Buff = (CFSecBuffSecSysRoleMemb)ensureRec(iBuff);
		CFSecBuffSecSysRoleMembPKey pkey = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		pkey.setRequiredSecSysRoleId(Buff.getRequiredSecSysRoleId());
		pkey.setRequiredLoginId(Buff.getRequiredLoginId());
		pkey.setRequiredSecSysRoleId( Buff.getRequiredSecSysRoleId() );
		pkey.setRequiredLoginId( Buff.getRequiredLoginId() );
		Buff.setRequiredContainerSysRole( pkey.getRequiredSecSysRoleId() );
		Buff.setRequiredParentUser( pkey.getRequiredLoginId() );
		Buff.setRequiredSecSysRoleId( pkey.getRequiredSecSysRoleId() );
		Buff.setRequiredLoginId( pkey.getRequiredLoginId() );
		CFSecBuffSecSysRoleMembBySysRoleIdxKey keySysRoleIdx = (CFSecBuffSecSysRoleMembBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newBySysRoleIdxKey();
		keySysRoleIdx.setRequiredSecSysRoleId( Buff.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecSysRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newByLoginIdxKey();
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
				if( null == schema.getTableSecSysRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						S_ProcName,
						"Container",
						"Container",
						"SecSysRoleMembSysRole",
						"SecSysRoleMembSysRole",
						"SecSysRole",
						"SecSysRole",
						null );
				}
			}
		}

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdictSysRoleIdx;
		if( dictBySysRoleIdx.containsKey( keySysRoleIdx ) ) {
			subdictSysRoleIdx = dictBySysRoleIdx.get( keySysRoleIdx );
		}
		else {
			subdictSysRoleIdx = new HashMap< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb >();
			dictBySysRoleIdx.put( keySysRoleIdx, subdictSysRoleIdx );
		}
		subdictSysRoleIdx.put( pkey, Buff );

		Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdictLoginIdx;
		if( dictByLoginIdx.containsKey( keyLoginIdx ) ) {
			subdictLoginIdx = dictByLoginIdx.get( keyLoginIdx );
		}
		else {
			subdictLoginIdx = new HashMap< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb >();
			dictByLoginIdx.put( keyLoginIdx, subdictLoginIdx );
		}
		subdictLoginIdx.put( pkey, Buff );

		if (Buff == null) {
			return( null );
		}
		else {
			int classCode = Buff.getClassCode();
			if (classCode == ICFSecSecSysRoleMemb.CLASS_CODE) {
				CFSecBuffSecSysRoleMemb retbuff = ((CFSecBuffSecSysRoleMemb)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newRec()));
				retbuff.set(Buff);
				return( retbuff );
			}
			else {
				throw new CFLibUnsupportedClassException(getClass(), S_ProcName, "-create-buff-cloning-", (Integer)classCode, "Classcode not recognized: " + Integer.toString(classCode));
			}
		}
	}

	@Override
	public ICFSecSecSysRoleMemb readDerived( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId,
		$implIJavaAtomType$ LoginId )
	{
		{	$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ testSecSysRoleId = SecSysRoleId;
			if (testSecSysRoleId == null) {
				return( null );
			}
		}
		{	$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ testLoginId = LoginId;
			if (testLoginId == null) {
				return( null );
			}
		}
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredLoginId( LoginId );
		return( readDerived( Authorization, key ) );
	}

	public ICFSecSecSysRoleMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readDerived";
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( PKey.getRequiredSecSysRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecSysRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.lockDerived";
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( PKey.getRequiredSecSysRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		ICFSecSecSysRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readAllDerived";
		ICFSecSecSysRoleMemb[] retList = new ICFSecSecSysRoleMemb[ dictByPKey.values().size() ];
		Iterator< CFSecBuffSecSysRoleMemb > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	@Override
	public ICFSecSecSysRoleMemb[] readDerivedBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readDerivedBySysRoleIdx";
		CFSecBuffSecSysRoleMembBySysRoleIdxKey key = (CFSecBuffSecSysRoleMembBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newBySysRoleIdxKey();

		key.setRequiredSecSysRoleId( SecSysRoleId );
		ICFSecSecSysRoleMemb[] recArray;
		if( dictBySysRoleIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdictSysRoleIdx
				= dictBySysRoleIdx.get( key );
			recArray = new ICFSecSecSysRoleMemb[ subdictSysRoleIdx.size() ];
			Iterator< CFSecBuffSecSysRoleMemb > iter = subdictSysRoleIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdictSysRoleIdx
				= new HashMap< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb >();
			dictBySysRoleIdx.put( key, subdictSysRoleIdx );
			recArray = new ICFSecSecSysRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysRoleMemb[] readDerivedByLoginIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readDerivedByLoginIdx";
		CFSecBuffSecSysRoleMembByLoginIdxKey key = (CFSecBuffSecSysRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newByLoginIdxKey();

		key.setRequiredLoginId( LoginId );
		ICFSecSecSysRoleMemb[] recArray;
		if( dictByLoginIdx.containsKey( key ) ) {
			Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdictLoginIdx
				= dictByLoginIdx.get( key );
			recArray = new ICFSecSecSysRoleMemb[ subdictLoginIdx.size() ];
			Iterator< CFSecBuffSecSysRoleMemb > iter = subdictLoginIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdictLoginIdx
				= new HashMap< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb >();
			dictByLoginIdx.put( key, subdictLoginIdx );
			recArray = new ICFSecSecSysRoleMemb[0];
		}
		return( recArray );
	}

	@Override
	public ICFSecSecSysRoleMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readDerivedByIdIdx() ";
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredLoginId( LoginId );
		ICFSecSecSysRoleMemb buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleMemb readRec( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId,
		$implIJavaAtomType$ LoginId )
	{
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredLoginId( LoginId );
		return( readRec( Authorization, key ) );
	}

	@Override
	public ICFSecSecSysRoleMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembPKey PKey )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readRec";
		ICFSecSecSysRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		ICFSecSecSysRoleMemb buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( buff.getClassCode() != ICFSecSecSysRoleMemb.CLASS_CODE ) ) {
			buff = null;
		}
		return( buff );
	}

	@Override
	public ICFSecSecSysRoleMemb[] readAllRec( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readAllRec";
		ICFSecSecSysRoleMemb buff;
		ArrayList<ICFSecSecSysRoleMemb> filteredList = new ArrayList<ICFSecSecSysRoleMemb>();
		ICFSecSecSysRoleMemb[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleMemb.CLASS_CODE ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRoleMemb[0] ) );
	}

	/**
	 *	Read a page of all the specific SecSysRoleMemb buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysRoleMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysRoleMemb[] pageAllRec( ICFSecAuthorization Authorization,
		$implIJavaOptAtomType$ priorSecSysRoleId,
		$implIJavaOptAtomType$ priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysRoleMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readRecByIdIdx() ";
		ICFSecSecSysRoleMemb buff = readDerivedByIdIdx( Authorization,
			SecSysRoleId,
			LoginId );
		if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleMemb.CLASS_CODE ) ) {
			return( (ICFSecSecSysRoleMemb)buff );
		}
		else {
			return( null );
		}
	}

	@Override
	public ICFSecSecSysRoleMemb[] readRecBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readRecBySysRoleIdx() ";
		ICFSecSecSysRoleMemb buff;
		ArrayList<ICFSecSecSysRoleMemb> filteredList = new ArrayList<ICFSecSecSysRoleMemb>();
		ICFSecSecSysRoleMemb[] buffList = readDerivedBySysRoleIdx( Authorization,
			SecSysRoleId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRoleMemb[0] ) );
	}

	@Override
	public ICFSecSecSysRoleMemb[] readRecByLoginIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ LoginId )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMemb.readRecByLoginIdx() ";
		ICFSecSecSysRoleMemb buff;
		ArrayList<ICFSecSecSysRoleMemb> filteredList = new ArrayList<ICFSecSecSysRoleMemb>();
		ICFSecSecSysRoleMemb[] buffList = readDerivedByLoginIdx( Authorization,
			LoginId );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && ( buff.getClassCode() == ICFSecSecSysRoleMemb.CLASS_CODE ) ) {
				filteredList.add( (ICFSecSecSysRoleMemb)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecSysRoleMemb[0] ) );
	}

	/**
	 *	Read a page array of the specific SecSysRoleMemb buffer instances identified by the duplicate key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleMemb[] pageRecBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId,
		$implIJavaOptAtomType$ priorSecSysRoleId,
		$implIJavaOptAtomType$ priorLoginId )
	{
		final String S_ProcName = "pageRecBySysRoleIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecSysRoleMemb buffer instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecSysRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleMemb[] pageRecByLoginIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ LoginId,
		$implIJavaOptAtomType$ priorSecSysRoleId,
		$implIJavaOptAtomType$ priorLoginId )
	{
		final String S_ProcName = "pageRecByLoginIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	@Override
	public ICFSecSecSysRoleMemb updateSecSysRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMemb iBuff )
	{
		CFSecBuffSecSysRoleMemb Buff = (CFSecBuffSecSysRoleMemb)ensureRec(iBuff);
		CFSecBuffSecSysRoleMembPKey pkey = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		pkey = (CFSecBuffSecSysRoleMembPKey)Buff.getPKey();
		CFSecBuffSecSysRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecSysRoleMemb",
				"Existing record not found",
				"Existing record not found",
				"SecSysRoleMemb",
				"SecSysRoleMemb",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecSysRoleMemb",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecSysRoleMembBySysRoleIdxKey existingKeySysRoleIdx = (CFSecBuffSecSysRoleMembBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newBySysRoleIdxKey();
		existingKeySysRoleIdx.setRequiredSecSysRoleId( existing.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleMembBySysRoleIdxKey newKeySysRoleIdx = (CFSecBuffSecSysRoleMembBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newBySysRoleIdxKey();
		newKeySysRoleIdx.setRequiredSecSysRoleId( Buff.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleMembByLoginIdxKey existingKeyLoginIdx = (CFSecBuffSecSysRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newByLoginIdxKey();
		existingKeyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecSysRoleMembByLoginIdxKey newKeyLoginIdx = (CFSecBuffSecSysRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newByLoginIdxKey();
		newKeyLoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		// Check unique indexes

		// Validate foreign keys

		{
			boolean allNull = true;

			if( allNull ) {
				if( null == schema.getTableSecSysRole().readDerivedByIdIdx( Authorization,
						Buff.getRequiredSecSysRoleId() ) )
				{
					throw new CFLibUnresolvedRelationException( getClass(),
						"updateSecSysRoleMemb",
						"Container",
						"Container",
						"SecSysRoleMembSysRole",
						"SecSysRoleMembSysRole",
						"SecSysRole",
						"SecSysRole",
						null );
				}
			}
		}

		// Update is valid

		Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		subdict = dictBySysRoleIdx.get( existingKeySysRoleIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictBySysRoleIdx.containsKey( newKeySysRoleIdx ) ) {
			subdict = dictBySysRoleIdx.get( newKeySysRoleIdx );
		}
		else {
			subdict = new HashMap< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb >();
			dictBySysRoleIdx.put( newKeySysRoleIdx, subdict );
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
			subdict = new HashMap< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb >();
			dictByLoginIdx.put( newKeyLoginIdx, subdict );
		}
		subdict.put( pkey, Buff );

		return(Buff);
	}

	@Override
	public void deleteSecSysRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMemb iBuff )
	{
		final String S_ProcName = "CFSecRamSecSysRoleMembTable.deleteSecSysRoleMemb() ";
		CFSecBuffSecSysRoleMemb Buff = (CFSecBuffSecSysRoleMemb)ensureRec(iBuff);
		int classCode;
		CFSecBuffSecSysRoleMembPKey pkey = (CFSecBuffSecSysRoleMembPKey)(Buff.getPKey());
		CFSecBuffSecSysRoleMemb existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecSysRoleMemb",
				pkey );
		}
		CFSecBuffSecSysRoleMembBySysRoleIdxKey keySysRoleIdx = (CFSecBuffSecSysRoleMembBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newBySysRoleIdxKey();
		keySysRoleIdx.setRequiredSecSysRoleId( existing.getRequiredSecSysRoleId() );

		CFSecBuffSecSysRoleMembByLoginIdxKey keyLoginIdx = (CFSecBuffSecSysRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newByLoginIdxKey();
		keyLoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecBuffSecSysRoleMembPKey, CFSecBuffSecSysRoleMemb > subdict;

		dictByPKey.remove( pkey );

		subdict = dictBySysRoleIdx.get( keySysRoleIdx );
		subdict.remove( pkey );

		subdict = dictByLoginIdx.get( keyLoginIdx );
		subdict.remove( pkey );

	}
	@Override
	public void deleteSecSysRoleMembByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ SecSysRoleId,
		$implIJavaAtomType$ LoginId )
	{
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( SecSysRoleId );
		key.setRequiredLoginId( LoginId );
		deleteSecSysRoleMembByIdIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembPKey PKey )
	{
		CFSecBuffSecSysRoleMembPKey key = (CFSecBuffSecSysRoleMembPKey)(schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newPKey());
		key.setRequiredSecSysRoleId( PKey.getRequiredSecSysRoleId() );
		key.setRequiredLoginId( PKey.getRequiredLoginId() );
		CFSecBuffSecSysRoleMembPKey argKey = key;
		boolean anyNotNull = false;
		anyNotNull = true;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecBuffSecSysRoleMemb cur;
		LinkedList<CFSecBuffSecSysRoleMemb> matchSet = new LinkedList<CFSecBuffSecSysRoleMemb>();
		Iterator<CFSecBuffSecSysRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRoleMemb)(schema.getTableSecSysRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecSysRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysRoleMembBySysRoleIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argSecSysRoleId )
	{
		CFSecBuffSecSysRoleMembBySysRoleIdxKey key = (CFSecBuffSecSysRoleMembBySysRoleIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newBySysRoleIdxKey();
		key.setRequiredSecSysRoleId( argSecSysRoleId );
		deleteSecSysRoleMembBySysRoleIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleMembBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembBySysRoleIdxKey argKey )
	{
		CFSecBuffSecSysRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysRoleMemb> matchSet = new LinkedList<CFSecBuffSecSysRoleMemb>();
		Iterator<CFSecBuffSecSysRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRoleMemb)(schema.getTableSecSysRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecSysRoleMemb( Authorization, cur );
		}
	}

	@Override
	public void deleteSecSysRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaAtomType first implIJavaAtomType each implCommaIJavaAtomType empty empty )$ argLoginId )
	{
		CFSecBuffSecSysRoleMembByLoginIdxKey key = (CFSecBuffSecSysRoleMembByLoginIdxKey)schema.getCFSecBuffFactory().getFactorySecSysRoleMemb().newByLoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecSysRoleMembByLoginIdx( Authorization, key );
	}

	@Override
	public void deleteSecSysRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleMembByLoginIdxKey argKey )
	{
		CFSecBuffSecSysRoleMemb cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecBuffSecSysRoleMemb> matchSet = new LinkedList<CFSecBuffSecSysRoleMemb>();
		Iterator<CFSecBuffSecSysRoleMemb> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecBuffSecSysRoleMemb> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = (CFSecBuffSecSysRoleMemb)(schema.getTableSecSysRoleMemb().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecSysRoleId(),
				cur.getRequiredLoginId() ));
			deleteSecSysRoleMemb( Authorization, cur );
		}
	}
}
